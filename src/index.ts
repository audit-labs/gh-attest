import { verifySignature, extractFact, extractRepoFullName, extractInstallationId } from "./webhook";
import {
  buildAuthorizeUrl,
  exchangeCodeForToken,
  fetchGithubUser,
  fetchUserInstallationIds,
  newSessionPayload,
  signSession,
  verifySession,
  SESSION_COOKIE,
  SESSION_TTL_SECONDS,
  STATE_COOKIE,
  STATE_TTL_SECONDS,
  type SessionPayload,
} from "./auth";
import { parseCookies, setCookieHeader, clearCookieHeader } from "./cookies";
import { createAppJwt, getInstallationToken } from "./github-app";
import { listInstallationRepos, pollRepoProtection, pollOrgAccess } from "./poller";
import { buildEvidenceRows, renderCsv, renderPdf, type Framework, type ExportFormat } from "./exporter";
import {
  renderDashboard,
  renderAccessReview,
  type ExportListRow,
  type InstallationOption,
} from "./dashboard";
import { buildAccessDiff } from "./access-review";

interface ExportJob {
  jobId: string;
  installationId: number;
  framework: Framework;
  format: ExportFormat;
}

const CONTENT_TYPE: Record<ExportFormat, string> = {
  csv: "text/csv; charset=utf-8",
  pdf: "application/pdf",
};

// Retention windows. Source of truth for retention; PRIVACY.md states the
// same periods, so the two must be changed together.
const SNAPSHOT_RETENTION_DAYS = 396; // ~13 months: an annual audit period + buffer
const EXPORT_RETENTION_DAYS = 90;

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "POST" && url.pathname === "/webhooks/github") {
      return handleWebhook(request, env);
    }
    if (request.method === "POST" && url.pathname === "/webhooks/marketplace") {
      return handleMarketplaceWebhook(request, env);
    }
    if (request.method === "GET" && url.pathname === "/login") {
      return handleLogin(request, env);
    }
    if (request.method === "GET" && url.pathname === "/callback") {
      return handleCallback(request, env);
    }
    if (request.method === "GET" && url.pathname === "/logout") {
      return handleLogout();
    }
    if (request.method === "POST" && url.pathname === "/admin/poll") {
      return handleAdminPoll(request, env);
    }
    if (request.method === "POST" && url.pathname === "/admin/export") {
      return handleAdminExport(request, env);
    }
    if (request.method === "POST" && url.pathname === "/admin/cleanup") {
      return handleAdminCleanup(request, env);
    }
    if (request.method === "POST" && url.pathname === "/admin/purge") {
      return handleAdminPurge(request, env);
    }
    const adminExportMatch = url.pathname.match(/^\/admin\/export\/([0-9a-f-]+)(\/download)?$/);
    if (request.method === "GET" && adminExportMatch) {
      const [, jobId, downloadSuffix] = adminExportMatch;
      if (jobId) return handleAdminExportGet(request, env, jobId, downloadSuffix === "/download");
    }
    // Dashboard (session-authed) surfaces.
    if (request.method === "POST" && url.pathname === "/resync") {
      return handleResync(request, env);
    }
    if (request.method === "POST" && url.pathname === "/exports") {
      return handleCreateExport(request, env);
    }
    if (request.method === "POST" && url.pathname === "/switch") {
      return handleSwitchInstallation(request, env);
    }
    const exportMatch = url.pathname.match(/^\/exports\/([0-9a-f-]+)(\/download)?$/);
    if (request.method === "GET" && exportMatch) {
      const [, jobId, downloadSuffix] = exportMatch;
      if (jobId) return handleSessionExportGet(request, env, jobId, downloadSuffix === "/download");
    }
    if (request.method === "GET" && url.pathname === "/access-review") {
      return handleAccessReview(request, env);
    }
    if (request.method === "GET" && url.pathname === "/") {
      return handleDashboard(request, env);
    }

    return new Response("Not found", { status: 404 });
  },

  async scheduled(_controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(
      Promise.all([pollAllInstallations(env), runRetentionCleanup(env)]).then(() => undefined),
    );
  },

  async queue(batch: MessageBatch<ExportJob>, env: Env): Promise<void> {
    for (const message of batch.messages) {
      try {
        await renderExport(env, message.body);
        message.ack();
      } catch (err) {
        const job = message.body;
        console.error(`Export ${job.jobId} failed:`, err);
        try {
          await env.DB.prepare(
            "UPDATE exports SET status = 'error', error = ?1, completed_at = ?2 WHERE id = ?3",
          )
            .bind((err as Error).message, new Date().toISOString(), job.jobId)
            .run();
        } catch (recordErr) {
          // Recording the failure must not stop the ack below, or a
          // deterministic render error would be retried to the DLQ limit.
          console.error(`Could not record export failure for ${job.jobId}:`, recordErr);
        }
        // Rendering failure is deterministic (bad data / bug), not transient —
        // don't retry, the error is recorded for the operator.
        message.ack();
      }
    }
  },
} satisfies ExportedHandler<Env, ExportJob>;

async function renderExport(env: Env, job: ExportJob): Promise<void> {
  await env.DB.prepare("UPDATE exports SET status = 'processing' WHERE id = ?1").bind(job.jobId).run();

  const rows = await buildEvidenceRows(env.DB, job.installationId, job.framework);
  const body =
    job.format === "pdf"
      ? await renderPdf(rows, {
          framework: job.framework,
          installationId: job.installationId,
          generatedAt: new Date().toISOString(),
        })
      : renderCsv(rows);
  const r2Key = `exports/${job.installationId}/${job.jobId}.${job.format}`;

  await env.EXPORTS.put(r2Key, body, {
    httpMetadata: { contentType: CONTENT_TYPE[job.format] },
  });

  await env.DB.prepare(
    "UPDATE exports SET status = 'done', r2_key = ?1, completed_at = ?2 WHERE id = ?3",
  )
    .bind(r2Key, new Date().toISOString(), job.jobId)
    .run();
}

// Timing-safe bearer check against ADMIN_TOKEN. Returns true if authorized.
function checkAdminAuth(request: Request, env: Env): boolean {
  const auth = request.headers.get("Authorization");
  const encoder = new TextEncoder();
  const provided = encoder.encode(auth ?? "");
  const want = encoder.encode(`Bearer ${env.ADMIN_TOKEN}`);
  return provided.length === want.length && crypto.subtle.timingSafeEqual(provided, want);
}

interface PollSummary {
  installationsPolled: number;
  written: Array<{ installationId: number; repo: string; resource: string; status: string }>;
  errors: string[];
}

// Baseline/drift poll for branch protection + ruleset state, since webhooks
// only fire on changes — a repo protected before the App was installed
// would otherwise never show up. Sequential per repo/installation is fine
// at test-org scale; a large multi-org install would need to fan this out
// through a Queue instead of looping inline in one scheduled invocation.
async function pollAllInstallations(env: Env): Promise<PollSummary> {
  const { results: installations } = await env.DB.prepare(
    "SELECT installation_id FROM installations WHERE suspended_at IS NULL",
  ).all<{ installation_id: number }>();

  const summary: PollSummary = { installationsPolled: installations.length, written: [], errors: [] };

  for (const { installation_id } of installations) {
    try {
      await pollInstallation(env, installation_id, summary);
    } catch (err) {
      const msg = `Poll failed for installation ${installation_id}: ${(err as Error).message}`;
      console.error(msg);
      summary.errors.push(msg);
    }
  }

  return summary;
}

async function pollInstallation(env: Env, installationId: number, summary: PollSummary): Promise<void> {
  const appJwt = await createAppJwt(env.GITHUB_APP_ID, env.GITHUB_APP_PRIVATE_KEY);
  const installationToken = await getInstallationToken(appJwt, installationId);
  const repos = await listInstallationRepos(installationToken);
  const capturedAt = new Date().toISOString();

  for (const repo of repos) {
    // Per-repo isolation: one failing repo must not abort the rest of the
    // installation's poll.
    try {
      const facts = await pollRepoProtection(installationToken, repo);
      for (const fact of facts) {
        await env.DB.prepare(
          `INSERT INTO snapshots (installation_id, repo, resource, status, raw_payload, captured_at)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6)`,
        )
          .bind(installationId, fact.repo, fact.resource, fact.status, fact.rawPayload, capturedAt)
          .run();
        summary.written.push({ installationId, repo: fact.repo, resource: fact.resource, status: fact.status });
      }
    } catch (err) {
      const msg = `Poll failed for repo ${repo.fullName}: ${(err as Error).message}`;
      console.error(msg);
      summary.errors.push(msg);
    }
  }

  await pollAccess(env, installationId, installationToken, capturedAt, summary);
}

// Org membership + team membership, for the access-review diff. Isolated from
// the repo poll so a failure here doesn't lose the posture data above.
async function pollAccess(
  env: Env,
  installationId: number,
  installationToken: string,
  capturedAt: string,
  summary: PollSummary,
): Promise<void> {
  try {
    const orgRow = await env.DB.prepare("SELECT org_login FROM installations WHERE installation_id = ?1")
      .bind(installationId)
      .first<{ org_login: string }>();
    if (!orgRow?.org_login) return;

    const facts = await pollOrgAccess(installationToken, orgRow.org_login);
    if (facts === null) {
      // Installed on a personal account, not an org — no membership to review.
      return;
    }

    for (const fact of facts) {
      await env.DB.prepare(
        `INSERT INTO snapshots (installation_id, repo, resource, status, raw_payload, captured_at, subject)
         VALUES (?1, NULL, ?2, ?3, NULL, ?4, ?5)`,
      )
        .bind(installationId, fact.resource, fact.status, capturedAt, fact.subject)
        .run();
      summary.written.push({
        installationId,
        repo: fact.subject,
        resource: fact.resource,
        status: fact.status,
      });
    }
  } catch (err) {
    const msg = `Access poll failed for installation ${installationId}: ${(err as Error).message}`;
    console.error(msg);
    summary.errors.push(msg);
  }
}

// Manual on-demand poll — same work as the scheduled handler, but callable
// via HTTP so an operator (or eventually a dashboard "re-sync now" button)
// can trigger it without waiting for the cron. Bearer-token guarded.
async function handleAdminPoll(request: Request, env: Env): Promise<Response> {
  if (!checkAdminAuth(request, env)) return new Response("Unauthorized", { status: 401 });
  const summary = await pollAllInstallations(env);
  return Response.json(summary);
}

// Enqueue an evidence export. Returns the job id; rendering happens off the
// request path in the queue consumer (PDF/large CSV can exceed request CPU).
async function handleAdminExport(request: Request, env: Env): Promise<Response> {
  if (!checkAdminAuth(request, env)) return new Response("Unauthorized", { status: 401 });

  const params = (await request.json().catch(() => ({}))) as {
    installationId?: number;
    framework?: string;
    format?: string;
  };
  const framework = normalizeFramework(params.framework);
  if (!framework) {
    return new Response("framework must be soc2, iso27001, or all", { status: 400 });
  }
  const format = params.format ?? "csv";
  if (format !== "csv" && format !== "pdf") {
    return new Response("format must be csv or pdf", { status: 400 });
  }

  const installIds = params.installationId
    ? [params.installationId]
    : (
        await env.DB.prepare("SELECT installation_id FROM installations WHERE suspended_at IS NULL").all<{
          installation_id: number;
        }>()
      ).results.map((r) => r.installation_id);

  const jobs: ExportJob[] = [];
  for (const installationId of installIds) {
    jobs.push(await enqueueExport(env, installationId, framework, format));
  }

  return Response.json({ jobs }, { status: 202 });
}

// Create the export job row + enqueue it. Shared by the admin (bearer) and
// dashboard (session) entry points.
async function enqueueExport(
  env: Env,
  installationId: number,
  framework: Framework,
  format: ExportFormat,
): Promise<ExportJob> {
  const jobId = crypto.randomUUID();
  await env.DB.prepare(
    `INSERT INTO exports (id, installation_id, framework, format, status, created_at)
     VALUES (?1, ?2, ?3, ?4, 'queued', ?5)`,
  )
    .bind(jobId, installationId, framework, format, new Date().toISOString())
    .run();
  const job: ExportJob = { jobId, installationId, framework, format };
  try {
    await env.GENERATE_EXPORT.send(job);
  } catch (err) {
    // Otherwise the row sits at 'queued' forever with nothing to process it.
    await env.DB.prepare(
      "UPDATE exports SET status = 'error', error = ?1, completed_at = ?2 WHERE id = ?3",
    )
      .bind(`Failed to enqueue: ${(err as Error).message}`, new Date().toISOString(), jobId)
      .run();
    throw err;
  }
  return job;
}

// R2 caps the number of keys per bulk delete, so chunk rather than let a
// large purge fail wholesale.
const R2_DELETE_BATCH = 1000;

async function deleteR2Objects(env: Env, keys: string[]): Promise<void> {
  for (let i = 0; i < keys.length; i += R2_DELETE_BATCH) {
    await env.EXPORTS.delete(keys.slice(i, i + R2_DELETE_BATCH));
  }
}

// Delete everything we hold for one installation: R2 export objects, then
// all D1 rows. Triggered by the `installation.deleted` webhook (uninstall)
// and available on request via /admin/purge.
async function purgeInstallation(env: Env, installationId: number): Promise<void> {
  const { results } = await env.DB.prepare(
    "SELECT r2_key FROM exports WHERE installation_id = ?1 AND r2_key IS NOT NULL",
  )
    .bind(installationId)
    .all<{ r2_key: string }>();
  await deleteR2Objects(env, results.map((r) => r.r2_key));

  await env.DB.batch([
    env.DB.prepare("DELETE FROM snapshots WHERE installation_id = ?1").bind(installationId),
    env.DB.prepare("DELETE FROM exports WHERE installation_id = ?1").bind(installationId),
    env.DB.prepare("DELETE FROM installations WHERE installation_id = ?1").bind(installationId),
  ]);
}

interface CleanupResult {
  snapshotsDeleted: number;
  exportsDeleted: number;
}

// Enforce the retention windows: drop snapshots and export files (D1 rows +
// R2 objects) past their age limit. Runs hourly from the scheduled handler;
// a no-op most of the time.
async function runRetentionCleanup(env: Env): Promise<CleanupResult> {
  const now = Date.now();
  const snapshotCutoff = new Date(now - SNAPSHOT_RETENTION_DAYS * 86400_000).toISOString();
  const exportCutoff = new Date(now - EXPORT_RETENTION_DAYS * 86400_000).toISOString();

  // Delete expired export R2 objects first (their keys live in the rows).
  const { results: expiredExports } = await env.DB.prepare(
    "SELECT r2_key FROM exports WHERE created_at < ?1 AND r2_key IS NOT NULL",
  )
    .bind(exportCutoff)
    .all<{ r2_key: string }>();
  await deleteR2Objects(env, expiredExports.map((r) => r.r2_key));

  const exportsRes = await env.DB.prepare("DELETE FROM exports WHERE created_at < ?1").bind(exportCutoff).run();
  const snapshotsRes = await env.DB.prepare("DELETE FROM snapshots WHERE captured_at < ?1")
    .bind(snapshotCutoff)
    .run();

  return {
    snapshotsDeleted: snapshotsRes.meta.changes ?? 0,
    exportsDeleted: exportsRes.meta.changes ?? 0,
  };
}

async function handleAdminCleanup(request: Request, env: Env): Promise<Response> {
  if (!checkAdminAuth(request, env)) return new Response("Unauthorized", { status: 401 });
  return Response.json(await runRetentionCleanup(env));
}

// On-request deletion of a specific installation's data (a documented
// deletion trigger). Bearer-guarded.
async function handleAdminPurge(request: Request, env: Env): Promise<Response> {
  if (!checkAdminAuth(request, env)) return new Response("Unauthorized", { status: 401 });
  const params = (await request.json().catch(() => ({}))) as { installationId?: number };
  if (typeof params.installationId !== "number") {
    return new Response("installationId (number) is required", { status: 400 });
  }
  await purgeInstallation(env, params.installationId);
  return Response.json({ purged: params.installationId });
}

// GET /admin/export/:id -> job status JSON; /admin/export/:id/download -> file.
// Admin (bearer) variant: no installation scoping.
async function handleAdminExportGet(request: Request, env: Env, jobId: string, download: boolean): Promise<Response> {
  if (!checkAdminAuth(request, env)) return new Response("Unauthorized", { status: 401 });
  const job = await env.DB.prepare(
    "SELECT id, installation_id, framework, format, status, r2_key, error, created_at, completed_at FROM exports WHERE id = ?1",
  )
    .bind(jobId)
    .first<{ status: string; r2_key: string | null; format: ExportFormat }>();
  return serveExport(env, job, jobId, download);
}

// Stream a finished export, or return its status JSON. `job` is already
// scoped/authorized by the caller.
async function serveExport(
  env: Env,
  job: { status: string; r2_key: string | null; format: ExportFormat } | null,
  jobId: string,
  download: boolean,
): Promise<Response> {
  if (!job) return new Response("Not found", { status: 404 });
  if (!download) return Response.json(job);

  if (job.status !== "done" || !job.r2_key) {
    return new Response(`Export not ready (status: ${job.status})`, { status: 409 });
  }
  const object = await env.EXPORTS.get(job.r2_key);
  if (!object) return new Response("Export file missing", { status: 410 });

  return new Response(object.body, {
    headers: {
      "Content-Type": CONTENT_TYPE[job.format],
      "Content-Disposition": `attachment; filename="${jobId}.${job.format}"`,
    },
  });
}

function normalizeFramework(value: string | undefined): Framework | null {
  if (value === undefined || value === "all") return "all";
  if (value === "soc2" || value === "iso27001") return value;
  return null;
}

async function requireSession(request: Request, env: Env): Promise<SessionPayload | null> {
  const token = parseCookies(request)[SESSION_COOKIE];
  return token ? verifySession(token, env.SESSION_SECRET) : null;
}

// Authenticated dashboard: current compliance posture + export controls,
// scoped to the logged-in user's installation.
async function handleDashboard(request: Request, env: Env): Promise<Response> {
  const session = await requireSession(request, env);
  if (!session) return new Response(null, { status: 302, headers: { Location: "/login" } });

  const url = new URL(request.url);
  const framework = normalizeFramework(url.searchParams.get("framework") ?? undefined) ?? "all";

  const [rows, orgRow, exportsResult, lastPollRow, installations] = await Promise.all([
    buildEvidenceRows(env.DB, session.installationId, framework),
    env.DB.prepare("SELECT org_login FROM installations WHERE installation_id = ?1")
      .bind(session.installationId)
      .first<{ org_login: string }>(),
    env.DB.prepare(
      `SELECT id, framework, format, status, created_at FROM exports
       WHERE installation_id = ?1 ORDER BY created_at DESC LIMIT 10`,
    )
      .bind(session.installationId)
      .all<ExportListRow>(),
    env.DB.prepare(
      `SELECT MAX(captured_at) AS t FROM snapshots
       WHERE installation_id = ?1 AND resource IN ('branch_protection', 'repository_ruleset')`,
    )
      .bind(session.installationId)
      .first<{ t: string | null }>(),
    accessibleInstallations(env, session),
  ]);

  const html = renderDashboard({
    login: session.login,
    installationId: session.installationId,
    orgLogin: orgRow?.org_login ?? "unknown",
    installations,
    framework,
    rows,
    exports: exportsResult.results,
    lastPolledAt: lastPollRow?.t ?? null,
  });

  return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
}

// Installations this session may view, with their org names, for the header
// switcher. Falls back to the single active id for sessions issued before
// the switcher existed.
async function accessibleInstallations(env: Env, session: SessionPayload): Promise<InstallationOption[]> {
  const ids = session.installationIds?.length ? session.installationIds : [session.installationId];
  const placeholders = ids.map(() => "?").join(",");
  const { results } = await env.DB.prepare(
    `SELECT installation_id, org_login FROM installations
     WHERE installation_id IN (${placeholders}) ORDER BY org_login`,
  )
    .bind(...ids)
    .all<InstallationOption>();
  return results;
}

// POST /switch — change which installation the session is viewing. The
// allowed set lives in the signed session, so a tampered id can't widen
// access beyond what was granted at login.
async function handleSwitchInstallation(request: Request, env: Env): Promise<Response> {
  const session = await requireSession(request, env);
  if (!session) return new Response("Unauthorized", { status: 401 });

  const form = await request.formData();
  const requested = Number(form.get("installationId"));
  const allowed = session.installationIds?.length ? session.installationIds : [session.installationId];
  if (!Number.isInteger(requested) || !allowed.includes(requested)) {
    return new Response("No access to that installation", { status: 403 });
  }

  const rotated = await signSession({ ...session, installationId: requested }, env.SESSION_SECRET);
  // Keep the original expiry — switching views shouldn't extend the session.
  const remaining = Math.max(0, session.exp - Math.floor(Date.now() / 1000));
  const headers = new Headers({ Location: form.get("return") === "access-review" ? "/access-review" : "/" });
  headers.append("Set-Cookie", setCookieHeader(SESSION_COOKIE, rotated, remaining));
  return new Response(null, { status: 303, headers });
}

// GET /access-review — membership changes since a chosen date, for the
// periodic access review auditors ask for.
async function handleAccessReview(request: Request, env: Env): Promise<Response> {
  const session = await requireSession(request, env);
  if (!session) return new Response(null, { status: 302, headers: { Location: "/login" } });

  const url = new URL(request.url);
  // Default comparison point: 30 days ago. An unparseable ?since= falls back
  // rather than throwing — Date#toISOString raises on an invalid date, so a
  // stale bookmark or empty form submit would otherwise 500 the page.
  const sinceParam = url.searchParams.get("since");
  const requested = sinceParam ? new Date(`${sinceParam}T23:59:59.999Z`) : null;
  const since =
    requested && !Number.isNaN(requested.getTime())
      ? requested.toISOString()
      : new Date(Date.now() - 30 * 86400_000).toISOString();

  const [diff, orgRow, installations] = await Promise.all([
    buildAccessDiff(env.DB, session.installationId, since),
    env.DB.prepare("SELECT org_login FROM installations WHERE installation_id = ?1")
      .bind(session.installationId)
      .first<{ org_login: string }>(),
    accessibleInstallations(env, session),
  ]);

  const html = renderAccessReview({
    login: session.login,
    installationId: session.installationId,
    orgLogin: orgRow?.org_login ?? "unknown",
    installations,
    since,
    diff,
  });
  return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
}

// POST /exports — session-authed export of the user's own installation.
async function handleCreateExport(request: Request, env: Env): Promise<Response> {
  const session = await requireSession(request, env);
  if (!session) return new Response("Unauthorized", { status: 401 });

  const form = await request.formData();
  const framework = normalizeFramework(String(form.get("framework") ?? "all")) ?? "all";
  const format: ExportFormat = String(form.get("format")) === "pdf" ? "pdf" : "csv";

  await enqueueExport(env, session.installationId, framework, format);
  return Response.redirect(new URL("/", request.url).toString(), 303);
}

// GET /exports/:id[/download] — session-authed, scoped to the user's
// installation so one org can't read another's export by guessing an id.
async function handleSessionExportGet(request: Request, env: Env, jobId: string, download: boolean): Promise<Response> {
  const session = await requireSession(request, env);
  if (!session) return new Response("Unauthorized", { status: 401 });

  const job = await env.DB.prepare(
    "SELECT id, framework, format, status, r2_key, created_at FROM exports WHERE id = ?1 AND installation_id = ?2",
  )
    .bind(jobId, session.installationId)
    .first<{ status: string; r2_key: string | null; format: ExportFormat }>();

  return serveExport(env, job, jobId, download);
}

// POST /resync — run the poll for the user's installation inline so the
// dashboard shows fresh state on the redirect. One installation's repos are
// few enough to finish within the request.
async function handleResync(request: Request, env: Env): Promise<Response> {
  const session = await requireSession(request, env);
  if (!session) return new Response("Unauthorized", { status: 401 });

  const summary: PollSummary = { installationsPolled: 1, written: [], errors: [] };
  try {
    await pollInstallation(env, session.installationId, summary);
  } catch (err) {
    console.error(`Resync failed for installation ${session.installationId}:`, err);
  }
  return Response.redirect(new URL("/", request.url).toString(), 303);
}

function handleLogin(request: Request, env: Env): Response {
  const state = crypto.randomUUID();
  const redirectUri = new URL("/callback", request.url).toString();
  const authorizeUrl = buildAuthorizeUrl(env, redirectUri, state);

  return new Response(null, {
    status: 302,
    headers: {
      Location: authorizeUrl,
      "Set-Cookie": setCookieHeader(STATE_COOKIE, state, STATE_TTL_SECONDS),
    },
  });
}

async function handleCallback(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const cookies = parseCookies(request);

  if (!code || !state || !cookies[STATE_COOKIE] || cookies[STATE_COOKIE] !== state) {
    return new Response("Invalid OAuth state", { status: 400 });
  }

  const redirectUri = new URL("/callback", request.url).toString();

  let accessToken: string;
  try {
    accessToken = await exchangeCodeForToken(env, code, redirectUri);
  } catch (err) {
    return new Response(`OAuth exchange failed: ${(err as Error).message}`, { status: 502 });
  }

  const [user, userInstallationIds] = await Promise.all([
    fetchGithubUser(accessToken),
    fetchUserInstallationIds(accessToken),
  ]);

  if (userInstallationIds.length === 0) {
    return new Response("No accessible installations of this App", { status: 403 });
  }

  // Cross-check against installations we actually track, so a user who can
  // see the App on some unrelated installation can't log into this one.
  // Ordered by org so a user in several installations lands somewhere
  // deterministic rather than on whichever row the DB happened to return.
  const placeholders = userInstallationIds.map(() => "?").join(",");
  const { results: known } = await env.DB.prepare(
    `SELECT installation_id FROM installations
     WHERE installation_id IN (${placeholders})
     ORDER BY org_login`,
  )
    .bind(...userInstallationIds)
    .all<{ installation_id: number }>();

  const accessibleIds = known.map((k) => k.installation_id);
  const defaultInstallationId = accessibleIds[0];
  if (defaultInstallationId === undefined) {
    return new Response("You don't have access to any org with this App installed", { status: 403 });
  }

  const session = await signSession(
    newSessionPayload(user, defaultInstallationId, accessibleIds),
    env.SESSION_SECRET,
  );

  const headers = new Headers({ Location: "/" });
  headers.append("Set-Cookie", setCookieHeader(SESSION_COOKIE, session, SESSION_TTL_SECONDS));
  headers.append("Set-Cookie", clearCookieHeader(STATE_COOKIE));

  return new Response(null, { status: 302, headers });
}

function handleLogout(): Response {
  return new Response(null, {
    status: 302,
    headers: {
      Location: "/login",
      "Set-Cookie": clearCookieHeader(SESSION_COOKIE),
    },
  });
}

// GitHub's webhook settings offer JSON or x-www-form-urlencoded, and the
// latter wraps the payload in a `payload` field. Accept either so flipping
// that setting can't 500 every delivery. Returns the canonical JSON text
// alongside the parsed object, since the raw JSON is what we retain for the
// audit trail.
function parseWebhookBody(
  bodyText: string,
  contentType: string | null,
): { payload: Record<string, unknown>; json: string } | null {
  const json = (contentType ?? "").includes("x-www-form-urlencoded")
    ? (new URLSearchParams(bodyText).get("payload") ?? "")
    : bodyText;
  try {
    return { payload: JSON.parse(json) as Record<string, unknown>, json };
  } catch {
    return null;
  }
}

// Marketplace listing events (marketplace_purchase). The listing is free, so
// there is no billing to run — this records who subscribed and is the place
// to add entitlement logic if paid plans are ever introduced. Kept separate
// from the App webhook because the payload carries no installation and would
// otherwise be discarded as "no installation context".
async function handleMarketplaceWebhook(request: Request, env: Env): Promise<Response> {
  const rawBody = await request.arrayBuffer();
  const valid = await verifySignature(rawBody, request.headers.get("X-Hub-Signature-256"), env.GITHUB_WEBHOOK_SECRET);
  if (!valid) return new Response("Invalid signature", { status: 401 });

  const parsed = parseWebhookBody(
    new TextDecoder().decode(rawBody),
    request.headers.get("Content-Type"),
  );
  if (!parsed) return new Response("Unparseable payload", { status: 400 });
  const { payload } = parsed;

  const purchase = payload.marketplace_purchase as Record<string, unknown> | undefined;
  const account = purchase?.account as Record<string, unknown> | undefined;
  const plan = purchase?.plan as Record<string, unknown> | undefined;
  console.log("marketplace event", {
    action: payload.action,
    account: account?.login,
    plan: plan?.name,
  });

  return new Response("OK", { status: 200 });
}

async function handleWebhook(request: Request, env: Env): Promise<Response> {
  const rawBody = await request.arrayBuffer();
  const signature = request.headers.get("X-Hub-Signature-256");
  const eventType = request.headers.get("X-GitHub-Event");

  if (!eventType) {
    return new Response("Missing X-GitHub-Event header", { status: 400 });
  }

  const valid = await verifySignature(rawBody, signature, env.GITHUB_WEBHOOK_SECRET);
  if (!valid) {
    return new Response("Invalid signature", { status: 401 });
  }

  const parsed = parseWebhookBody(
    new TextDecoder().decode(rawBody),
    request.headers.get("Content-Type"),
  );
  if (!parsed) return new Response("Unparseable payload", { status: 400 });
  const { payload, json: bodyText } = parsed;

  const installationId = extractInstallationId(payload);
  if (installationId === null) {
    // No installation context (e.g. an event type outside the app's install scope) — nothing to attribute a snapshot to.
    return new Response("OK (no installation context)", { status: 202 });
  }

  // Installation lifecycle: uninstall purges all data; suspend/unsuspend
  // toggle processing without deleting. Other actions (created,
  // new_permissions_accepted) fall through to the normal snapshot path.
  if (eventType === "installation") {
    const action = typeof payload.action === "string" ? payload.action : "";
    if (action === "deleted") {
      await purgeInstallation(env, installationId);
      return new Response("OK (purged)", { status: 200 });
    }
    if (action === "suspend") {
      await env.DB.prepare("UPDATE installations SET suspended_at = ?2 WHERE installation_id = ?1")
        .bind(installationId, new Date().toISOString())
        .run();
      return new Response("OK (suspended)", { status: 200 });
    }
    if (action === "unsuspend") {
      await env.DB.prepare("UPDATE installations SET suspended_at = NULL WHERE installation_id = ?1")
        .bind(installationId)
        .run();
      return new Response("OK (unsuspended)", { status: 200 });
    }
  }

  const orgLogin = extractOrgLogin(payload);
  const capturedAt = new Date().toISOString();

  await env.DB.prepare(
    `INSERT INTO installations (installation_id, org_login, installed_at)
     VALUES (?1, ?2, ?3)
     ON CONFLICT(installation_id) DO NOTHING`,
  )
    .bind(installationId, orgLogin, capturedAt)
    .run();

  const fact = extractFact(eventType, payload);
  const repo = extractRepoFullName(payload);

  await env.DB.prepare(
    `INSERT INTO snapshots (installation_id, repo, resource, status, raw_payload, captured_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6)`,
  )
    .bind(installationId, repo, fact.resource, fact.status, bodyText, capturedAt)
    .run();

  return new Response("OK", { status: 200 });
}

function extractOrgLogin(payload: Record<string, unknown>): string {
  const installation = payload.installation as Record<string, unknown> | undefined;
  const account = installation?.account as Record<string, unknown> | undefined;
  if (typeof account?.login === "string") return account.login;

  const organization = payload.organization as Record<string, unknown> | undefined;
  if (typeof organization?.login === "string") return organization.login;

  return "unknown";
}
