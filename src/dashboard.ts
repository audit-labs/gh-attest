import type { EvidenceRow, Framework } from "./exporter";

export interface ExportListRow {
  id: string;
  framework: string;
  format: string;
  status: string;
  created_at: string;
}

export interface InstallationOption {
  installation_id: number;
  org_login: string;
}

// Shown only when the user can see more than one installation; a single-org
// user gets the plain org name instead of a pointless dropdown.
function installationSwitcher(
  installations: InstallationOption[],
  current: number,
  returnTo: "dashboard" | "access-review",
): string {
  if (installations.length < 2) return "";
  const options = installations
    .map(
      (i) =>
        `<option value="${esc(i.installation_id)}"${i.installation_id === current ? " selected" : ""}>${esc(
          i.org_login,
        )}</option>`,
    )
    .join("");
  return `<form method="post" action="/switch" class="switcher">
      <input type="hidden" name="return" value="${esc(returnTo)}">
      <select name="installationId" onchange="this.form.submit()">${options}</select>
      <noscript><button type="submit">Switch</button></noscript>
    </form>`;
}

export interface DashboardData {
  login: string;
  installationId: number;
  orgLogin: string;
  installations: InstallationOption[];
  framework: Framework;
  rows: EvidenceRow[];
  exports: ExportListRow[];
  lastPolledAt: string | null;
}

function esc(value: unknown): string {
  return String(value ?? "").replace(/[&<>"']/g, (c) => {
    switch (c) {
      case "&": return "&amp;";
      case "<": return "&lt;";
      case ">": return "&gt;";
      case '"': return "&quot;";
      default: return "&#39;";
    }
  });
}

const STYLE = `
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { margin: 0; font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         color: #1a1a1a; background: #f6f7f9; }
  header { display: flex; align-items: baseline; justify-content: space-between; gap: 1rem;
           padding: 1rem 1.5rem; background: #fff; border-bottom: 1px solid #e2e5e9; flex-wrap: wrap; }
  header h1 { font-size: 1.05rem; margin: 0; }
  header .who { color: #666; font-size: 0.85rem; }
  header .who a { color: #0055dc; margin-left: 0.75rem; }
  main { max-width: 1100px; margin: 0 auto; padding: 1.5rem; }
  .cards { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.5rem; }
  .card { flex: 1 1 120px; background: #fff; border: 1px solid #e2e5e9; border-radius: 8px; padding: 0.9rem 1rem; }
  .card .n { font-size: 1.6rem; font-weight: 600; }
  .card .l { color: #666; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.03em; }
  .n.positive { color: #1a8039; } .n.negative { color: #b32626; } .n.informational { color: #666; }
  .bar { display: flex; gap: 1rem; align-items: center; flex-wrap: wrap; margin-bottom: 1rem; }
  .bar .filters a { margin-right: 0.5rem; text-decoration: none; color: #0055dc; padding: 0.2rem 0.5rem; border-radius: 5px; }
  .bar .filters a.active { background: #0055dc; color: #fff; }
  form { display: inline-flex; gap: 0.4rem; align-items: center; margin: 0; }
  input, select, button { font: inherit; padding: 0.35rem 0.6rem; border: 1px solid #c9ced6; border-radius: 6px; background: #fff; }
  button { cursor: pointer; background: #0055dc; color: #fff; border-color: #0055dc; }
  button.secondary { background: #fff; color: #1a1a1a; }
  table { width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #e2e5e9; border-radius: 8px; overflow: hidden; }
  th, td { text-align: left; padding: 0.5rem 0.75rem; border-bottom: 1px solid #eef0f3; font-size: 0.85rem; }
  th { background: #fafbfc; font-weight: 600; color: #444; }
  tr:last-child td { border-bottom: none; }
  .posture { font-weight: 600; }
  .posture.positive { color: #1a8039; } .posture.negative { color: #b32626; } .posture.informational { color: #888; }
  .section-title { font-size: 1rem; margin: 2rem 0 0.75rem; }
  .muted { color: #888; }
  code { background: #eef0f3; padding: 0.1rem 0.3rem; border-radius: 4px; font-size: 0.85em; }
`;

export function renderDashboard(data: DashboardData): string {
  const counts = { positive: 0, negative: 0, informational: 0 };
  const repos = new Set<string>();
  for (const r of data.rows) {
    counts[r.posture as keyof typeof counts] = (counts[r.posture as keyof typeof counts] ?? 0) + 1;
    if (r.repo) repos.add(r.repo);
  }

  const frameworkTab = (value: Framework, label: string) =>
    `<a href="/?framework=${value}" class="${data.framework === value ? "active" : ""}">${label}</a>`;

  const evidenceRows = data.rows
    .map(
      (r) => `<tr>
        <td>${esc(r.framework)}</td>
        <td>${esc(r.control_id)}</td>
        <td class="posture ${esc(r.posture)}">${esc(r.posture)}</td>
        <td>${esc(r.repo ?? r.subject ?? "—")}</td>
        <td>${esc(r.resource)}</td>
        <td>${esc(r.status)}</td>
      </tr>`,
    )
    .join("");

  const exportRows = data.exports
    .map((e) => {
      const done = e.status === "done";
      const cell = done
        ? `<a href="/exports/${esc(e.id)}/download">Download ${esc(e.format.toUpperCase())}</a>`
        : `<span class="muted" data-export-id="${esc(e.id)}">${esc(e.status)}…</span>`;
      return `<tr>
        <td>${esc(e.created_at)}</td>
        <td>${esc(e.framework)}</td>
        <td>${esc(e.format.toUpperCase())}</td>
        <td class="export-status">${cell}</td>
      </tr>`;
    })
    .join("");

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>gh-attest — Compliance Evidence</title>
  <style>${STYLE}</style>
</head>
<body>
  <header>
    <h1>gh-attest — Compliance Evidence</h1>
    <div class="who">${esc(data.login)} ·
      ${installationSwitcher(data.installations, data.installationId, "dashboard") || esc(data.orgLogin)}
      <a href="/access-review">Access review</a><a href="/logout">Log out</a></div>
  </header>
  <main>
    <div class="cards">
      <div class="card"><div class="n negative">${counts.negative}</div><div class="l">Gaps</div></div>
      <div class="card"><div class="n positive">${counts.positive}</div><div class="l">Satisfied</div></div>
      <div class="card"><div class="n informational">${counts.informational}</div><div class="l">Informational</div></div>
      <div class="card"><div class="n">${repos.size}</div><div class="l">Repositories</div></div>
    </div>

    <div class="bar">
      <div class="filters">
        ${frameworkTab("all", "All")}
        ${frameworkTab("soc2", "SOC 2")}
        ${frameworkTab("iso27001", "ISO 27001")}
      </div>
      <form method="post" action="/resync">
        <button class="secondary" type="submit">Re-sync now</button>
      </form>
      <form method="post" action="/exports">
        <input type="hidden" name="framework" value="${esc(data.framework)}">
        <select name="format">
          <option value="csv">CSV</option>
          <option value="pdf">PDF</option>
        </select>
        <button type="submit">Generate export</button>
      </form>
    </div>

    <p class="muted">${
      data.lastPolledAt ? `Last synced ${esc(data.lastPolledAt)}` : "Not yet synced — click Re-sync now."
    }</p>

    <table>
      <thead><tr><th>Framework</th><th>Control</th><th>Posture</th><th>Repo / Subject</th><th>Resource</th><th>Status</th></tr></thead>
      <tbody>${evidenceRows || `<tr><td colspan="6" class="muted">No evidence yet.</td></tr>`}</tbody>
    </table>

    <h2 class="section-title">Recent exports</h2>
    <table>
      <thead><tr><th>Created</th><th>Framework</th><th>Format</th><th>File</th></tr></thead>
      <tbody>${exportRows || `<tr><td colspan="4" class="muted">No exports yet.</td></tr>`}</tbody>
    </table>
  </main>

  <script>
    // Poll any pending exports and swap in the download link when ready.
    for (const el of document.querySelectorAll("[data-export-id]")) {
      const id = el.getAttribute("data-export-id");
      const tick = async () => {
        const r = await fetch("/exports/" + id, { headers: { accept: "application/json" } });
        if (!r.ok) return;
        const job = await r.json();
        if (job.status === "done") {
          el.closest(".export-status").innerHTML =
            '<a href="/exports/' + id + '/download">Download ' + String(job.format).toUpperCase() + "</a>";
        } else if (job.status === "error") {
          el.textContent = "error";
        } else {
          setTimeout(tick, 3000);
        }
      };
      setTimeout(tick, 3000);
    }
  </script>
</body>
</html>`;
}

export interface AccessReviewData {
  login: string;
  installationId: number;
  orgLogin: string;
  installations: InstallationOption[];
  since: string;
  diff: import("./access-review").AccessDiff;
}

const CHANGE_CLASS: Record<string, string> = {
  added: "negative", // new access is what an access review scrutinises
  removed: "positive",
  changed: "informational",
};

export function renderAccessReview(data: AccessReviewData): string {
  const { diff } = data;

  const rows = diff.entries
    .map(
      (e) => `<tr>
        <td class="posture ${esc(CHANGE_CLASS[e.change] ?? "informational")}">${esc(e.change)}</td>
        <td>${esc(e.resource === "org_member" ? "org member" : "team member")}</td>
        <td>${esc(e.subject)}</td>
        <td>${esc(e.from ?? "—")}</td>
        <td>${esc(e.to ?? "—")}</td>
      </tr>`,
    )
    .join("");

  let banner: string;
  if (!diff.currentAt) {
    banner = `<p class="muted">No access data collected yet. Access review requires the App to be
      installed on an <strong>organization</strong> (personal accounts have no membership to review),
      and at least one sync to have run.</p>`;
  } else if (!diff.priorAt) {
    banner = `<p class="muted">Baseline captured ${esc(diff.currentAt)} (${diff.currentCount} access
      entries). No earlier snapshot before ${esc(data.since)} to compare against yet — the next sync
      after that date will produce a diff.</p>`;
  } else {
    banner = `<p class="muted">Comparing ${esc(diff.priorAt)} → ${esc(diff.currentAt)} ·
      ${diff.currentCount} current access entries · ${diff.entries.length} change(s).</p>`;
  }

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>gh-attest — Access Review</title>
  <style>${STYLE}</style>
</head>
<body>
  <header>
    <h1>gh-attest — Access Review</h1>
    <div class="who">${esc(data.login)} ·
      ${installationSwitcher(data.installations, data.installationId, "access-review") || esc(data.orgLogin)}
      <a href="/">Dashboard</a><a href="/logout">Log out</a></div>
  </header>
  <main>
    <div class="bar">
      <form method="get" action="/access-review">
        <label for="since">Compare against</label>
        <input id="since" type="date" name="since" value="${esc(data.since.slice(0, 10))}">
        <button type="submit">Update</button>
      </form>
    </div>

    ${banner}

    <table>
      <thead><tr><th>Change</th><th>Type</th><th>Subject</th><th>Was</th><th>Now</th></tr></thead>
      <tbody>${rows || `<tr><td colspan="5" class="muted">No membership changes in this window.</td></tr>`}</tbody>
    </table>
  </main>
</body>
</html>`;
}
