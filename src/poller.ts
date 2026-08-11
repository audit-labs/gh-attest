const GITHUB_API = "https://api.github.com";

function authHeaders(installationToken: string): HeadersInit {
  return {
    Authorization: `Bearer ${installationToken}`,
    Accept: "application/vnd.github+json",
    "User-Agent": "gh-attest",
  };
}

export interface RepoRef {
  fullName: string;
  owner: string;
  name: string;
  defaultBranch: string;
}

export async function listInstallationRepos(installationToken: string): Promise<RepoRef[]> {
  const repos: RepoRef[] = [];
  let page = 1;

  for (;;) {
    const res = await fetch(`${GITHUB_API}/installation/repositories?per_page=100&page=${page}`, {
      headers: authHeaders(installationToken),
    });
    if (!res.ok) throw new Error(`Failed to list installation repositories (${res.status})`);

    const data = (await res.json()) as {
      repositories: Array<{ full_name: string; default_branch: string }>;
    };
    if (data.repositories.length === 0) break;

    for (const repo of data.repositories) {
      const separatorIndex = repo.full_name.indexOf("/");
      const owner = repo.full_name.slice(0, separatorIndex);
      const name = repo.full_name.slice(separatorIndex + 1);
      repos.push({ fullName: repo.full_name, owner, name, defaultBranch: repo.default_branch });
    }

    if (data.repositories.length < 100) break;
    page++;
  }

  return repos;
}

interface ProtectionCheck {
  status: "enabled" | "disabled" | "unavailable";
  raw: unknown;
}

async function fetchBranchProtection(
  installationToken: string,
  owner: string,
  repo: string,
  branch: string,
): Promise<ProtectionCheck> {
  const res = await fetch(`${GITHUB_API}/repos/${owner}/${repo}/branches/${branch}/protection`, {
    headers: authHeaders(installationToken),
  });
  if (res.status === 404) return { status: "disabled", raw: null };
  // 403 = feature not available on this repo's plan (e.g. private repo on a
  // free account). Recorded as "unavailable" — deliberately unmapped in
  // control_mappings so it never counts as evidence either way.
  if (res.status === 403) return { status: "unavailable", raw: null };
  if (!res.ok) throw new Error(`Failed to fetch branch protection for ${owner}/${repo} (${res.status})`);

  return { status: "enabled", raw: await res.json() };
}

async function fetchDefaultBranchRules(
  installationToken: string,
  owner: string,
  repo: string,
  branch: string,
): Promise<ProtectionCheck> {
  // /rules/branches/{branch} aggregates the rules from every ACTIVE ruleset —
  // repo- and org-level — that applies to this branch. Evaluate-mode
  // (monitor-only) rulesets are excluded, and a ruleset targeting only other
  // branches contributes nothing, so a non-empty result means the default
  // branch is actually covered by at least one enforcing ruleset.
  const res = await fetch(
    `${GITHUB_API}/repos/${owner}/${repo}/rules/branches/${encodeURIComponent(branch)}?per_page=100`,
    { headers: authHeaders(installationToken) },
  );
  // 403 = feature not available; 404 = branch not found (e.g. empty repo).
  // Both deliberately unmapped, like branch protection's "unavailable".
  if (res.status === 403 || res.status === 404) return { status: "unavailable", raw: null };
  if (!res.ok) throw new Error(`Failed to fetch branch rules for ${owner}/${repo} (${res.status})`);

  const rules = (await res.json()) as unknown[];
  return { status: rules.length > 0 ? "enabled" : "disabled", raw: rules };
}

export interface PolledFact {
  repo: string;
  resource: string;
  status: string;
  subject: string | null;
  rawPayload: string | null;
}

export async function pollRepoProtection(installationToken: string, repo: RepoRef): Promise<PolledFact[]> {
  const [branchProtection, rulesets] = await Promise.all([
    fetchBranchProtection(installationToken, repo.owner, repo.name, repo.defaultBranch),
    fetchDefaultBranchRules(installationToken, repo.owner, repo.name, repo.defaultBranch),
  ]);

  return [
    {
      repo: repo.fullName,
      resource: "branch_protection",
      status: branchProtection.status,
      subject: null,
      rawPayload: branchProtection.raw ? JSON.stringify(branchProtection.raw) : null,
    },
    {
      repo: repo.fullName,
      resource: "repository_ruleset",
      status: rulesets.status,
      subject: null,
      rawPayload: rulesets.raw ? JSON.stringify(rulesets.raw) : null,
    },
  ];
}

// ---------------------------------------------------------------------------
// Alert streams: baseline + keep-alive poll.
// ---------------------------------------------------------------------------

// The list endpoint doubles as the tooling-enabled signal: 200 means the
// feature is on regardless of whether it has ever produced an alert, 404
// means it is switched off, 403 means it is not available (plan / GHAS).
// Only `enabled` is mapped in control_mappings — absence of the tooling is
// recorded but never counted as evidence either way.
const ALERT_FEATURES = [
  { feature: "dependabot", alertResource: "dependabot_alert", path: "/dependabot/alerts" },
  { feature: "code_scanning", alertResource: "code_scanning_alert", path: "/code-scanning/alerts" },
  { feature: "secret_scanning", alertResource: "secret_scanning_alert", path: "/secret-scanning/alerts" },
] as const;

interface AlertsCheck {
  feature: "enabled" | "disabled" | "unavailable";
  alerts: Array<{ number: number; state: string }>;
}

// Both offset (code/secret scanning) and cursor (Dependabot) pagination
// advertise the next page in the Link header.
function nextPageUrl(linkHeader: string | null): string | null {
  const match = linkHeader?.match(/<([^>]+)>;\s*rel="next"/);
  return match?.[1] ?? null;
}

async function fetchOpenAlerts(
  installationToken: string,
  owner: string,
  repo: string,
  path: string,
): Promise<AlertsCheck> {
  const alerts: AlertsCheck["alerts"] = [];
  let url: string | null = `${GITHUB_API}/repos/${owner}/${repo}${path}?state=open&per_page=100`;
  while (url) {
    const res: Response = await fetch(url, { headers: authHeaders(installationToken) });
    if (res.status === 404) return { feature: "disabled", alerts: [] };
    if (res.status === 403) return { feature: "unavailable", alerts: [] };
    if (!res.ok) throw new Error(`Failed to list ${path} for ${owner}/${repo} (${res.status})`);

    const page = (await res.json()) as Array<{ number: number; state: string }>;
    for (const alert of page) alerts.push({ number: alert.number, state: alert.state });
    url = nextPageUrl(res.headers.get("Link"));
  }
  return { feature: "enabled", alerts };
}

// Webhooks record alert transitions, but (a) alerts already open before the
// App was installed never sent one, and (b) an open alert with no events for
// the whole retention window would age out of evidence. Re-recording the open
// set every poll fixes both. Subrequest cost is 3+ per repo, on top of the 2
// for protection state.
export async function pollRepoAlerts(installationToken: string, repo: RepoRef): Promise<PolledFact[]> {
  const facts: PolledFact[] = [];
  for (const { feature, alertResource, path } of ALERT_FEATURES) {
    const check = await fetchOpenAlerts(installationToken, repo.owner, repo.name, path);
    facts.push({ repo: repo.fullName, resource: feature, status: check.feature, subject: null, rawPayload: null });
    for (const alert of check.alerts) {
      facts.push({
        repo: repo.fullName,
        resource: alertResource,
        status: alert.state,
        subject: String(alert.number),
        rawPayload: null,
      });
    }
  }
  return facts;
}

// ---------------------------------------------------------------------------
// Access review: org membership and team membership.
// ---------------------------------------------------------------------------

export interface AccessFact {
  resource: "org_member" | "team_member";
  subject: string; // member login, or "team-slug:login" for team membership
  status: string; // org role (admin|member) or team role (maintainer|member)
}

interface GithubUser {
  login: string;
}

async function listUsers(installationToken: string, path: string): Promise<string[]> {
  const logins: string[] = [];
  let page = 1;

  for (;;) {
    const separator = path.includes("?") ? "&" : "?";
    const res = await fetch(`${GITHUB_API}${path}${separator}per_page=100&page=${page}`, {
      headers: authHeaders(installationToken),
    });
    if (!res.ok) throw new Error(`Failed to list ${path} (${res.status})`);

    const users = (await res.json()) as GithubUser[];
    for (const user of users) logins.push(user.login);

    if (users.length < 100) break;
    page++;
  }

  return logins;
}

// Returns null when the installation account is a personal User rather than an
// Organization — there is no membership to review, which is not an error.
//
// Subrequest cost is 3 + (2 x team count); an org with very many teams would
// need to fan this out through a Queue rather than one scheduled invocation.
export async function pollOrgAccess(installationToken: string, orgLogin: string): Promise<AccessFact[] | null> {
  const orgRes = await fetch(`${GITHUB_API}/orgs/${orgLogin}`, { headers: authHeaders(installationToken) });
  if (orgRes.status === 404) return null;
  if (!orgRes.ok) throw new Error(`Failed to fetch org ${orgLogin} (${orgRes.status})`);

  const facts: AccessFact[] = [];

  for (const role of ["admin", "member"] as const) {
    for (const login of await listUsers(installationToken, `/orgs/${orgLogin}/members?role=${role}`)) {
      facts.push({ resource: "org_member", subject: login, status: role });
    }
  }

  const teamsRes = await fetch(`${GITHUB_API}/orgs/${orgLogin}/teams?per_page=100`, {
    headers: authHeaders(installationToken),
  });
  if (!teamsRes.ok) throw new Error(`Failed to list teams for ${orgLogin} (${teamsRes.status})`);
  const teams = (await teamsRes.json()) as Array<{ slug: string }>;

  for (const team of teams) {
    for (const role of ["maintainer", "member"] as const) {
      const path = `/orgs/${orgLogin}/teams/${team.slug}/members?role=${role}`;
      for (const login of await listUsers(installationToken, path)) {
        facts.push({ resource: "team_member", subject: `${team.slug}:${login}`, status: role });
      }
    }
  }

  return facts;
}
