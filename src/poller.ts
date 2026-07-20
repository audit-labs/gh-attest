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

async function fetchRulesets(installationToken: string, owner: string, repo: string): Promise<ProtectionCheck> {
  const res = await fetch(`${GITHUB_API}/repos/${owner}/${repo}/rulesets?per_page=100`, {
    headers: authHeaders(installationToken),
  });
  if (res.status === 403) return { status: "unavailable", raw: null };
  if (!res.ok) throw new Error(`Failed to fetch rulesets for ${owner}/${repo} (${res.status})`);

  const rulesets = (await res.json()) as Array<{ enforcement: string; target: string }>;
  // "evaluate" is dry-run/monitor-only — doesn't actually block anything, so
  // it doesn't count as protection being enabled.
  const enabled = rulesets.some((r) => r.enforcement === "active" && r.target === "branch");
  return { status: enabled ? "enabled" : "disabled", raw: rulesets };
}

export interface PolledFact {
  repo: string;
  resource: "branch_protection" | "repository_ruleset";
  status: "enabled" | "disabled" | "unavailable";
  rawPayload: string | null;
}

export async function pollRepoProtection(installationToken: string, repo: RepoRef): Promise<PolledFact[]> {
  const [branchProtection, rulesets] = await Promise.all([
    fetchBranchProtection(installationToken, repo.owner, repo.name, repo.defaultBranch),
    fetchRulesets(installationToken, repo.owner, repo.name),
  ]);

  return [
    {
      repo: repo.fullName,
      resource: "branch_protection",
      status: branchProtection.status,
      rawPayload: branchProtection.raw ? JSON.stringify(branchProtection.raw) : null,
    },
    {
      repo: repo.fullName,
      resource: "repository_ruleset",
      status: rulesets.status,
      rawPayload: rulesets.raw ? JSON.stringify(rulesets.raw) : null,
    },
  ];
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
